import React from 'react';

export default function SeverityPanel({ stats }) {
  const totalFlows = stats?.total_flows || 0;
  const severityCounts = stats?.severity_counts || { Critical: 0, High: 0, Medium: 0, Normal: 0 };
  const topAttackers = stats?.top_attackers || {};

  const getPercent = (count) => {
    if (totalFlows === 0) return 0;
    return Math.min(100, (count / totalFlows) * 100);
  };

  return (
    <div className="bg-soc-900 border border-soc-700 rounded-xl p-5 flex flex-col justify-between h-full">
      <div>
        <h2 className="text-sm font-bold tracking-wide text-white uppercase pb-3 border-b border-soc-700 flex items-center justify-between">
          <span>Severity Hierarchy</span>
          <span className="text-xs text-slate-400 font-normal">Classification Matrix</span>
        </h2>

        <div className="mt-4 space-y-3.5">
          {/* Critical */}
          <div>
            <div className="flex items-center justify-between text-xs mb-1 font-mono">
              <span className="text-red-400 font-bold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-red-500" /> CRITICAL: DDoS / DoS
              </span>
              <span className="text-red-300 font-bold">{severityCounts.Critical || 0}</span>
            </div>
            <div className="w-full bg-soc-800 rounded-full h-2 overflow-hidden">
              <div
                className="bg-red-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${getPercent(severityCounts.Critical || 0)}%` }}
              />
            </div>
          </div>

          {/* High */}
          <div>
            <div className="flex items-center justify-between text-xs mb-1 font-mono">
              <span className="text-orange-400 font-bold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-orange-500" /> HIGH: Brute Force
              </span>
              <span className="text-orange-300 font-bold">{severityCounts.High || 0}</span>
            </div>
            <div className="w-full bg-soc-800 rounded-full h-2 overflow-hidden">
              <div
                className="bg-orange-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${getPercent(severityCounts.High || 0)}%` }}
              />
            </div>
          </div>

          {/* Medium */}
          <div>
            <div className="flex items-center justify-between text-xs mb-1 font-mono">
              <span className="text-yellow-400 font-bold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-yellow-500" /> MEDIUM: Port Scan
              </span>
              <span className="text-yellow-300 font-bold">{severityCounts.Medium || 0}</span>
            </div>
            <div className="w-full bg-soc-800 rounded-full h-2 overflow-hidden">
              <div
                className="bg-yellow-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${getPercent(severityCounts.Medium || 0)}%` }}
              />
            </div>
          </div>

          {/* Normal */}
          <div>
            <div className="flex items-center justify-between text-xs mb-1 font-mono">
              <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500" /> NORMAL: Normal Traffic
              </span>
              <span className="text-emerald-300 font-bold">{severityCounts.Normal || 0}</span>
            </div>
            <div className="w-full bg-soc-800 rounded-full h-2 overflow-hidden">
              <div
                className="bg-emerald-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${getPercent(severityCounts.Normal || 0)}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Top Attack Sources */}
      <div className="mt-5 pt-4 border-t border-soc-700/80">
        <h3 className="text-xs font-bold uppercase text-slate-300 tracking-wider mb-2">Top Attack Sources</h3>
        {Object.keys(topAttackers).length === 0 ? (
          <div className="text-[11px] text-slate-500 font-mono">No attacking hosts recorded yet</div>
        ) : (
          <div className="space-y-1.5 font-mono text-xs">
            {Object.entries(topAttackers).slice(0, 5).map(([ip, count]) => (
              <div key={ip} className="flex justify-between items-center py-0.5">
                <span className="text-rose-400 font-medium">{ip}</span>
                <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 text-[11px] border border-rose-500/30">
                  {count} attack{count > 1 ? 's' : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
