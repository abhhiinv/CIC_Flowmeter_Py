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
    <div className="bg-[#1a1a1a] border border-[#2a2a2a] p-4 flex flex-col justify-between h-full font-mono text-xs">
      <div>
        <h2 className="text-xs font-bold tracking-wider text-[#ffffff] uppercase pb-2.5 border-b border-[#2a2a2a] flex items-center justify-between">
          <span>[ SEVERITY MATRIX ]</span>
          <span className="text-[11px] text-[#888888] font-normal">CLASSIFICATION</span>
        </h2>

        <div className="mt-3.5 space-y-3">
          {/* Critical */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-red-400 font-bold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-red-500" /> CRITICAL: DDoS / DoS
              </span>
              <span className="text-red-400 font-bold">{severityCounts.Critical || 0}</span>
            </div>
            <div className="w-full bg-[#0a0a0a] border border-[#2a2a2a] h-2 overflow-hidden">
              <div
                className="bg-red-500 h-full transition-all duration-300"
                style={{ width: `${getPercent(severityCounts.Critical || 0)}%` }}
              />
            </div>
          </div>

          {/* High */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-orange-400 font-bold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-orange-500" /> HIGH: Brute Force
              </span>
              <span className="text-orange-400 font-bold">{severityCounts.High || 0}</span>
            </div>
            <div className="w-full bg-[#0a0a0a] border border-[#2a2a2a] h-2 overflow-hidden">
              <div
                className="bg-orange-500 h-full transition-all duration-300"
                style={{ width: `${getPercent(severityCounts.High || 0)}%` }}
              />
            </div>
          </div>

          {/* Medium */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-yellow-400 font-bold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-yellow-500" /> MEDIUM: Port Scan
              </span>
              <span className="text-yellow-400 font-bold">{severityCounts.Medium || 0}</span>
            </div>
            <div className="w-full bg-[#0a0a0a] border border-[#2a2a2a] h-2 overflow-hidden">
              <div
                className="bg-yellow-500 h-full transition-all duration-300"
                style={{ width: `${getPercent(severityCounts.Medium || 0)}%` }}
              />
            </div>
          </div>

          {/* Normal */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[#00c853] font-bold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-[#00c853]" /> NORMAL: Benign Traffic
              </span>
              <span className="text-[#00c853] font-bold">{severityCounts.Normal || 0}</span>
            </div>
            <div className="w-full bg-[#0a0a0a] border border-[#2a2a2a] h-2 overflow-hidden">
              <div
                className="bg-[#00c853] h-full transition-all duration-300"
                style={{ width: `${getPercent(severityCounts.Normal || 0)}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Top Attack Sources */}
      <div className="mt-4 pt-3 border-t border-[#2a2a2a]">
        <h3 className="text-[11px] font-bold uppercase text-[#888888] tracking-wider mb-2">
          [ TOP ATTACK SOURCES ]
        </h3>
        {Object.keys(topAttackers).length === 0 ? (
          <div className="text-[11px] text-[#888888]">No attacking hosts recorded yet</div>
        ) : (
          <div className="space-y-1">
            {Object.entries(topAttackers).slice(0, 5).map(([ip, count]) => (
              <div key={ip} className="flex justify-between items-center py-0.5 border-b border-[#2a2a2a]/40 last:border-0">
                <span className="text-[#ffffff] font-medium">{ip}</span>
                <span className="px-1.5 py-0.2 border border-red-500/40 bg-[#0a0a0a] text-red-400 text-[10px]">
                  {count} hit{count > 1 ? 's' : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
