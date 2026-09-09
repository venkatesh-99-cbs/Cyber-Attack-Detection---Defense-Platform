import { HealthStatus, DashboardSummaryResponse, DashboardStatsResponse } from '../types/api';
import { EventListResponse } from '../types/event';
import { AlertListResponse } from '../types/alert';
import { IncidentListResponse } from '../types/incident';

const getBaseUrl = (): string => {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  return 'http://localhost:8000';
};

const API_BASE_URL = getBaseUrl();

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`HTTP Error ${response.status}: ${errorText || response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export const apiService = {
  getApiBaseUrl(): string {
    return API_BASE_URL;
  },

  async fetchHealth(): Promise<HealthStatus> {
    try {
      const res = await fetch(`${API_BASE_URL}/health`);
      return await handleResponse<HealthStatus>(res);
    } catch (err) {
      return { status: 'error' };
    }
  },

  async fetchSummary(): Promise<DashboardSummaryResponse | null> {
    try {
      const res = await fetch(`${API_BASE_URL}/dashboard/summary`);
      return await handleResponse<DashboardSummaryResponse>(res);
    } catch (err) {
      console.warn('Dashboard summary fetch failed:', err);
      return null;
    }
  },

  async fetchStatistics(): Promise<DashboardStatsResponse | null> {
    try {
      const res = await fetch(`${API_BASE_URL}/dashboard/statistics`);
      return await handleResponse<DashboardStatsResponse>(res);
    } catch (err) {
      console.warn('Dashboard statistics fetch failed:', err);
      return null;
    }
  },

  async fetchEvents(limit = 50, offset = 0): Promise<EventListResponse> {
    try {
      const res = await fetch(`${API_BASE_URL}/events?limit=${limit}&offset=${offset}`);
      return await handleResponse<EventListResponse>(res);
    } catch (err) {
      console.warn('Events list fetch failed:', err);
      return { total: 0, limit, offset, events: [] };
    }
  },

  async fetchAlerts(): Promise<AlertListResponse> {
    try {
      const res = await fetch(`${API_BASE_URL}/alerts`);
      return await handleResponse<AlertListResponse>(res);
    } catch (err) {
      return {
        persisted: false,
        status: 'DISCONNECTED',
        message: 'Backend API unavailable.',
        alerts: null,
      };
    }
  },

  async fetchIncidents(): Promise<IncidentListResponse> {
    try {
      const res = await fetch(`${API_BASE_URL}/incidents`);
      return await handleResponse<IncidentListResponse>(res);
    } catch (err) {
      return {
        persisted: false,
        status: 'DISCONNECTED',
        message: 'Backend API unavailable.',
        incidents: null,
      };
    }
  },
};
