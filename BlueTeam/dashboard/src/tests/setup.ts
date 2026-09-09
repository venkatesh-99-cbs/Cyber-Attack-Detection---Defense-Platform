import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mock ResizeObserver for Recharts
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}));

// Mock WebSocket for jsdom environment
class MockWebSocket {
  public readyState = 1;
  public onopen: (() => void) | null = null;
  public onmessage: ((ev: MessageEvent) => void) | null = null;
  public onerror: (() => void) | null = null;
  public onclose: (() => void) | null = null;

  constructor(public url: string) {
    setTimeout(() => {
      if (this.onopen) this.onopen();
    }, 10);
  }

  public close() {
    if (this.onclose) this.onclose();
  }

  public send() {}
}

(global as any).WebSocket = MockWebSocket;
