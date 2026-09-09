import React, { useState } from 'react';
import { Database, Search, Filter, ChevronLeft, ChevronRight, Eye, RefreshCw } from 'lucide-react';
import { SecurityEvent } from '../types/event';

interface EventTableProps {
  events: SecurityEvent[];
  total: number;
  limit: number;
  offset: number;
  isLoading?: boolean;
  onPageChange?: (newOffset: number) => void;
  onSelectEvent?: (event: SecurityEvent) => void;
  onRefresh?: () => void;
}

export const EventTable: React.FC<EventTableProps> = ({
  events,
  total,
  limit,
  offset,
  isLoading = false,
  onPageChange,
  onSelectEvent,
  onRefresh,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('ALL');

  // Filter events locally by search term or type
  const filteredEvents = events.filter((e) => {
    const matchesSearch =
      searchTerm === '' ||
      e.source_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.target_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.event_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (e.endpoint && e.endpoint.toLowerCase().includes(searchTerm.toLowerCase())) ||
      e.message.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesType = selectedType === 'ALL' || e.event_type === selectedType;

    return matchesSearch && matchesType;
  });

  const eventTypes = Array.from(new Set(events.map((e) => e.event_type)));

  const totalPages = Math.ceil(total / limit) || 1;
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg flex flex-col h-full overflow-hidden shadow-sm">
      {/* Table Header & Controls */}
      <div className="px-4 py-3 border-b border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-3 bg-soc-panel select-none">
        <div className="flex items-center space-x-2">
          <Database className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
            Security Event Logs
          </h3>
          <span className="bg-slate-800 text-slate-300 border border-slate-700 text-[10px] font-mono px-2 py-0.5 rounded font-medium">
            {total} Total
          </span>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          {/* Search Box */}
          <div className="relative flex-1 sm:w-48">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search IP, endpoint, ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-soc-bg border border-soc-border focus:border-sky-500/50 rounded text-xs text-slate-200 pl-8 pr-3 py-1.5 focus:outline-none placeholder-slate-500 transition-colors"
            />
          </div>

          {/* Event Type Filter */}
          {eventTypes.length > 0 && (
            <div className="flex items-center space-x-1 bg-soc-bg border border-soc-border px-2 py-1 rounded">
              <Filter className="w-3 h-3 text-slate-400" />
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="bg-transparent text-slate-200 text-xs font-mono focus:outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-soc-panel">All Types</option>
                {eventTypes.map((t) => (
                  <option key={t} value={t} className="bg-soc-panel">{t}</option>
                ))}
              </select>
            </div>
          )}

          {/* Refresh Button */}
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={isLoading}
              className="p-1.5 bg-soc-bg hover:bg-slate-800 text-slate-300 border border-soc-border rounded transition-colors disabled:opacity-50"
              title="Refresh events"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-sky-400' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* Table Content */}
      <div className="flex-1 overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs font-mono">
          <thead>
            <tr className="bg-soc-bg/80 text-soc-textMuted border-b border-soc-border uppercase text-[10px] tracking-wider select-none">
              <th className="py-2.5 px-3">ID</th>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Event Type</th>
              <th className="py-2.5 px-3">Source IP</th>
              <th className="py-2.5 px-3">Target IP</th>
              <th className="py-2.5 px-3">Endpoint / Details</th>
              <th className="py-2.5 px-3 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-borderMuted">
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-10 px-4 text-soc-textMuted">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <Database className="w-6 h-6 text-slate-600" />
                    <p className="text-xs font-mono text-slate-300">
                      {searchTerm || selectedType !== 'ALL'
                        ? 'No security events match the selected filters.'
                        : 'No security events recorded in database yet.'}
                    </p>
                    <p className="text-[11px] text-slate-500">
                      Post events to <code className="text-sky-400 font-mono">POST /events</code> to populate the database log.
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              filteredEvents.map((evt) => (
                <tr
                  key={evt.event_id}
                  className="hover:bg-soc-card/70 transition-colors group"
                >
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                    #{evt.id ?? '-'}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                    {new Date(evt.timestamp).toLocaleString()}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className="bg-slate-800 text-sky-300 px-2 py-0.5 rounded text-[11px] font-mono border border-slate-700">
                      {evt.event_type}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-200 whitespace-nowrap font-medium">
                    {evt.source_ip}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                    {evt.target_ip}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate">
                    {evt.endpoint ? (
                      <span className="space-x-1.5">
                        {evt.method && (
                          <span className="text-[10px] text-slate-400 font-bold bg-slate-900 px-1 py-0.2 rounded border border-slate-800">
                            {evt.method}
                          </span>
                        )}
                        <span className="text-slate-200">{evt.endpoint}</span>
                        {evt.status_code !== undefined && evt.status_code !== null && (
                          <span className={`text-[10px] px-1 py-0.2 rounded border ${
                            evt.status_code >= 400
                              ? 'text-rose-400 border-rose-500/30 bg-rose-950/40'
                              : 'text-emerald-400 border-emerald-500/30 bg-emerald-950/40'
                          }`}>
                            {evt.status_code}
                          </span>
                        )}
                      </span>
                    ) : (
                      <span className="text-slate-400 truncate">{evt.message}</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-right whitespace-nowrap">
                    <button
                      onClick={() => onSelectEvent && onSelectEvent(evt)}
                      className="inline-flex items-center space-x-1 text-[11px] font-mono text-sky-400 hover:text-sky-300 bg-slate-800/80 hover:bg-slate-800 px-2.5 py-1 rounded border border-slate-700 transition-colors"
                    >
                      <Eye className="w-3 h-3" />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {total > 0 && onPageChange && (
        <div className="px-4 py-2.5 border-t border-soc-border bg-soc-panel flex items-center justify-between text-xs font-mono text-soc-textMuted select-none">
          <div>
            Showing <strong className="text-slate-200">{events.length}</strong> of{' '}
            <strong className="text-slate-200">{total}</strong> events (Page {currentPage} of {totalPages})
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => onPageChange(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="p-1 rounded bg-soc-bg border border-soc-border text-slate-300 hover:text-slate-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              title="Previous Page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => onPageChange(offset + limit)}
              disabled={offset + limit >= total}
              className="p-1 rounded bg-soc-bg border border-soc-border text-slate-300 hover:text-slate-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              title="Next Page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
