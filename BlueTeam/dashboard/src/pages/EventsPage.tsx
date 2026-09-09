import React from 'react';
import { EventTable } from '../components/EventTable';
import { SecurityEvent } from '../types/event';

interface EventsPageProps {
  events: SecurityEvent[];
  total: number;
  limit: number;
  offset: number;
  isLoading: boolean;
  onPageChange: (newOffset: number) => void;
  onSelectEvent: (evt: SecurityEvent) => void;
  onRefresh: () => void;
}

export const EventsPage: React.FC<EventsPageProps> = ({
  events,
  total,
  limit,
  offset,
  isLoading,
  onPageChange,
  onSelectEvent,
  onRefresh,
}) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between px-1">
        <div>
          <h2 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
            Security Event Repository
          </h2>
          <p className="text-xs text-soc-textMuted mt-0.5 font-sans">
            Inspected raw security telemetry stored in SQLite <code className="text-sky-400 font-mono">security_events</code> table.
          </p>
        </div>
      </div>

      <div className="h-[calc(100vh-220px)] min-h-[500px]">
        <EventTable
          events={events}
          total={total}
          limit={limit}
          offset={offset}
          isLoading={isLoading}
          onPageChange={onPageChange}
          onSelectEvent={onSelectEvent}
          onRefresh={onRefresh}
        />
      </div>
    </div>
  );
};
