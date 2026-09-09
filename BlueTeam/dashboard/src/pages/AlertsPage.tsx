import React from 'react';
import { DataAvailabilityBanner } from '../components/DataAvailabilityBanner';
import { LiveAlertFeed } from '../components/LiveAlertFeed';
import { WebSocketAlertMessage } from '../types/alert';

interface AlertsPageProps {
  liveAlerts: WebSocketAlertMessage[];
  onClearLiveAlerts: () => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ liveAlerts, onClearLiveAlerts }) => {
  return (
    <div className="space-y-6">
      {/* Honest Data Availability Explanation Banner */}
      <DataAvailabilityBanner
        title="Historical Alert Persistence Not Configured"
        message="Alert objects are evaluated dynamically by the Blue Team AlertEngine during security pipeline execution and broadcast over WebSockets (/ws). Historical alert storage in SQLite is not configured in the current database schema stage."
        scope="alerts"
      />

      {/* Live Session Alerts Stream */}
      <div className="min-h-[500px]">
        <LiveAlertFeed alerts={liveAlerts} onClear={onClearLiveAlerts} />
      </div>
    </div>
  );
};
