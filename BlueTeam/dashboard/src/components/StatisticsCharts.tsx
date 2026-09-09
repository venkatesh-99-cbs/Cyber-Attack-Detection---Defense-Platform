import React from 'react';
import { BarChart2, PieChart as PieIcon } from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { DashboardStatsResponse } from '../types/api';

interface StatisticsChartsProps {
  stats: DashboardStatsResponse | null;
}

const COLOR_PALETTE = [
  '#38bdf8', // sky
  '#f59e0b', // amber
  '#10b981', // emerald
  '#a855f7', // purple
  '#ef4444', // red
  '#64748b', // slate
];

export const StatisticsCharts: React.FC<StatisticsChartsProps> = ({ stats }) => {
  if (!stats) {
    return (
      <div className="bg-soc-panel border border-soc-border rounded-lg p-6 text-center text-xs font-mono text-soc-textMuted">
        Loading security statistics...
      </div>
    );
  }

  // Convert events_by_type dictionary into Recharts format
  const typeData = Object.entries(stats.events_by_type || {}).map(([type, count]) => ({
    name: type,
    count: count,
  }));

  // Convert top_source_ips into Recharts format
  const ipData = (stats.top_source_ips || []).map((item) => ({
    ip: item.source_ip,
    count: item.count,
  }));

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Event Types Breakdown */}
      <div className="bg-soc-panel border border-soc-border rounded-lg p-4 flex flex-col h-72 shadow-sm">
        <div className="flex items-center space-x-2 border-b border-soc-border pb-3 mb-2 select-none">
          <PieIcon className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
            Event Types Distribution
          </h3>
        </div>

        {typeData.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-xs font-mono text-slate-500">
            No event type statistics recorded
          </div>
        ) : (
          <div className="flex-1 w-full h-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={typeData}
                  dataKey="count"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={75}
                  innerRadius={35}
                  paddingAngle={3}
                  label={({ name, count }) => `${name}: ${count}`}
                  labelLine={false}
                >
                  {typeData.map((_, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={COLOR_PALETTE[index % COLOR_PALETTE.length]}
                      stroke="#0f172a"
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                    color: '#f8fafc',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Top Source IPs */}
      <div className="bg-soc-panel border border-soc-border rounded-lg p-4 flex flex-col h-72 shadow-sm">
        <div className="flex items-center space-x-2 border-b border-soc-border pb-3 mb-2 select-none">
          <BarChart2 className="w-4 h-4 text-amber-400" />
          <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
            Top Source IPs by Volume
          </h3>
        </div>

        {ipData.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-xs font-mono text-slate-500">
            No source IP traffic recorded
          </div>
        ) : (
          <div className="flex-1 w-full h-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ipData} layout="vertical" margin={{ top: 5, right: 20, left: 40, bottom: 5 }}>
                <XAxis type="number" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <YAxis dataKey="ip" type="category" stroke="#64748b" tick={{ fill: '#cbd5e1', fontSize: 11 }} width={90} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                    color: '#f8fafc',
                  }}
                />
                <Bar dataKey="count" fill="#38bdf8" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
};
