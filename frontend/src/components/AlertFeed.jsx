import React from 'react';
import { SEVERITY_CONFIG } from '../constants';

export default function AlertFeed({ alerts, onSelectFlow }) {
  const visibleAlerts = alerts.slice(0, 15);

  return (
    <div className="bg-soc-900 border border-soc-700 rounded-xl flex flex-col overflow-hidden h-full">
      {/* Header */}
      <div className="px-5 py-3.5 border-b border-soc-700 flex items-center justify-between bg-soc-850/50">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
          <h2 className="text-sm font-bold tracking-wide text-white uppercase">Real-Time Threat Alerts</h2>
          <span className="text-xs px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 font-mono font-bold">
            {alerts.length}
          </span>
        </div>
        <span className="text-xs text-slate-400 font-mono">Priority Security Incidents</span>
      </div>

      {/* Feed content */}
      <div className="p-4 flex-1 overflow-y-auto max-h-[360px] space-y-2.5">
        {visibleAlerts.length === 0 ? (
          <div className="h-44 flex flex-col items-center justify-center text-slate-500 text-xs">
            <svg
              width="32"
              height="32"
              className="w-8 h-8 mb-2 text-slate-600"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
            No attack alerts recorded yet. Network traffic appears normal.
          </div>
        ) : (
          visibleAlerts.map((alert) => {
            const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.Medium;
            const timeStr = alert.timestamp ? (alert.timestamp.split(' ')[1] || alert.timestamp) : '--:--:--';

            return (
              <div
                key={`alert-${alert.id}-${alert.epoch || alert.timestamp}`}
                onClick={() => onSelectFlow(alert)}
                className={`p-3.5 rounded-lg bg-soc-800/80 hover:bg-soc-800 border transition cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${cfg.rowBorder}`}
              >
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono tracking-wider ${cfg.bgBadge}`}>
                    {cfg.label}
                  </span>
                  <div>
                    <div className="text-sm font-bold text-white flex items-center gap-2">
                      <span>{alert.label}</span>
                      <span className="text-xs text-slate-400 font-mono font-normal">
                        #{alert.id}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-slate-300 mt-0.5">
                      <span className="text-rose-400">{alert.src_ip}:{alert.src_port}</span>
                      <span className="text-slate-500 mx-1.5">&rarr;</span>
                      <span className="text-slate-300">{alert.dst_ip}:{alert.dst_port}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono self-end sm:self-center">
                  {alert.confidence !== null && alert.confidence !== undefined && (
                    <div className="text-right">
                      <div className="text-slate-400 text-[10px]">CONFIDENCE</div>
                      <div className="text-slate-200 font-bold">{(alert.confidence * 100).toFixed(1)}%</div>
                    </div>
                  )}
                  <div className="text-right">
                    <div className="text-slate-400 text-[10px]">TIME</div>
                    <div className="text-slate-300">{timeStr}</div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
