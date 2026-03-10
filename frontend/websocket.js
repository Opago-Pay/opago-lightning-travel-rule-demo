/**
 * websocket.js — No-op stub for opago Travel Rule Demo.
 * The demo runs entirely client-side with simulated flows.
 * This file is kept as a stub so existing script tags don't error.
 */

/* exported WebSocketClient */
/* eslint-disable no-unused-vars */

class WebSocketClient {
  constructor() {
    this.isConnected = false;
  }
  connect() {}
  send() { return false; }
  on() { return () => {}; }
  off() {}
  disconnect() {}
}

// Global instance (no-op)
window.wsClient = new WebSocketClient();
