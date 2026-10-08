import { useState, useEffect, useRef, useCallback } from 'react';
import { playAlertSound } from '../constants';

const INITIAL_STATS = {
  total_flows: 0,
  total_attacks: 0,
  normal_traffic: 0,
  attack_rate: 0.0,
  severity_counts: { Critical: 0, High: 0, Medium: 0, Normal: 0 },
  category_counts: { 'DDoS': 0, 'DoS': 0, 'Brute Force': 0, 'Port Scan': 0, 'Normal Traffic': 0 },
  top_attackers: {},
  top_targets: {},
  interface: 'Wi-Fi',
  ml_enabled: true,
  psd_enabled: true,
};

export function useWebSocket({ isPaused = false, soundEnabled = true } = {}) {
  const [connected, setConnected] = useState(false);
  const [flows, setFlows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(INITIAL_STATS);
  const [lastCriticalAlert, setLastCriticalAlert] = useState(null);

  // Keep refs for live values inside the WebSocket event listener
  const isPausedRef = useRef(isPaused);
  isPausedRef.current = isPaused;

  const soundEnabledRef = useRef(soundEnabled);
  soundEnabledRef.current = soundEnabled;

  const wsRef = useRef(null);

  const clearLastCritical = useCallback(() => {
    setLastCriticalAlert(null);
  }, []);

  useEffect(() => {
    let reconnectTimeout = null;
    let heartbeatInterval = null;
    let isMounted = true;

    const connect = () => {
      if (!isMounted) return;

      const loc = window.location;
      const protocol = loc.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${loc.host}/ws`;

      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        if (!isMounted) return;
        setConnected(true);
      };

      socket.onmessage = (event) => {
        if (!isMounted) return;
        try {
          const data = JSON.parse(event.data);

          if (data.type === 'init') {
            if (data.stats) setStats(data.stats);
            if (data.recent_flows) setFlows(data.recent_flows.slice(0, 200));
            if (data.recent_alerts) setAlerts(data.recent_alerts.slice(0, 100));
          } else if (data.type === 'flow') {
            const newFlow = data.flow;

            // Stats always update even when paused
            if (data.stats) {
              setStats(data.stats);
            }

            if (newFlow) {
              // Only push to flow table and alert feed if not paused
              if (!isPausedRef.current) {
                setFlows((prev) => [newFlow, ...prev].slice(0, 200));

                if (newFlow.is_attack) {
                  setAlerts((prev) => [newFlow, ...prev].slice(0, 100));
                }
              }

              // Critical alert banner updates
              if (newFlow.severity === 'Critical') {
                setLastCriticalAlert(newFlow);
              }

              // Audio alarm triggers if enabled
              if (newFlow.is_attack && soundEnabledRef.current) {
                playAlertSound(newFlow.severity);
              }
            }
          } else if (data.type === 'clear') {
            if (data.stats) {
              setStats(data.stats);
            } else {
              setStats(INITIAL_STATS);
            }
            setFlows([]);
            setAlerts([]);
            setLastCriticalAlert(null);
          }
        } catch (err) {
          // Silently handle non-JSON or ping/pong messages
        }
      };

      socket.onclose = () => {
        if (!isMounted) return;
        setConnected(false);
        reconnectTimeout = setTimeout(connect, 2000);
      };

      socket.onerror = () => {
        socket.close();
      };
    };

    connect();

    // 15-second heartbeat ping
    heartbeatInterval = setInterval(() => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping');
      }
    }, 15000);

    return () => {
      isMounted = false;
      clearTimeout(reconnectTimeout);
      clearInterval(heartbeatInterval);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  return {
    connected,
    flows,
    alerts,
    stats,
    lastCriticalAlert,
    clearLastCritical,
  };
}
