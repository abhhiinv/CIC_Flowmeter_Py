import React from 'react';
import { SEVERITY_CONFIG } from '../constants';

export default function AlertFeed({ alerts, onSelectFlow }) {
  const visibleAlerts = alerts.slice(0, 15);

  return (
    <div className="bg-[#1a1a1a] border border-[#2a2a2a] flex flex-col overflow-hidden h-full font-mono">
      {/* Header */}
      <div className="px-4 py-2.5 border-b border-[#2a2a2a] flex items-center justify-between bg-[#151515]">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 bg-red-500 animate-pulse" />
          <h2 className="text-xs font-bold tracking-wider text-[#ffffff] uppercase">
            [!] THREAT ALERT FEED
          </h2>
          <span className="text-xs px-1.5 py-0.2 border border-red-500/40 bg-[#0a0a0a] text-red-400 font-bold">
            {alerts.length}
          </span>
        </div>
        <span className="text-[11px] text-[#888888]">PRIORITY INCIDENTS</span>
      </div>

      {/* Feed content */}
      <div className="p-3 flex-1 overflow-y-auto max-h-[360px] space-y-2">
        {visibleAlerts.length === 0 ? (
          <div className="h-44 flex flex-col items-center justify-center text-[#888888] text-xs space-y-1">
            <span>[ -- NO ACTIVE THREAT ALERTS -- ]</span>
            <span className="text-[11px] text-[#888888]/80">Network traffic appears normal</span>
          </div>
        ) : (
          visibleAlerts.map((alert) => {
            const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.Medium;
            const timeStr = alert.timestamp ? (alert.timestamp.split(' ')[1] || alert.timestamp) : '--:--:--';

            return (
              <div
                key={`alert-${alert.id}-${alert.epoch || alert.timestamp}`}
                onClick={() => onSelectFlow(alert)}
                className={`p-2.5 bg-[#0a0a0a] border border-[#2a2a2a] hover:border-[#888888] transition cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5 ${cfg.rowBorder}`}
              >
                <div className="flex items-center gap-2.5">
                  <span className={`px-1.5 py-0.5 text-[10px] font-bold tracking-wider ${cfg.bgBadge}`}>
                    [{cfg.label}]
                  </span>
                  <div>
                    <div className="text-xs font-bold text-[#ffffff] flex items-center gap-2">
                      <span>{alert.label}</span>
                      <span className="text-[11px] text-[#888888] font-normal">
                        #{alert.id}
                      </span>
                    </div>
                    <div className="text-xs text-[#888888] mt-0.5">
                      <span className="text-red-400">{alert.src_ip}:{alert.src_port}</span>
                      <span className="text-[#888888] mx-1.5">&rarr;</span>
                      <span className="text-[#ffffff]">{alert.dst_ip}:{alert.dst_port}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 text-xs self-end sm:self-center">
                  {alert.confidence !== null && alert.confidence !== undefined && (
                    <div className="text-right">
                      <div className="text-[#888888] text-[10px]">CONF</div>
                      <div className="text-[#ffffff] font-bold">{(alert.confidence * 100).toFixed(1)}%</div>
                    </div>
                  )}
                  <div className="text-right">
                    <div className="text-[#888888] text-[10px]">TIME</div>
                    <div className="text-[#888888]">{timeStr}</div>
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
