import React from 'react';

export default function StatCards({ stats }) {
  const totalFlows = stats?.total_flows || 0;
  const normalTraffic = stats?.normal_traffic || 0;
  const totalAttacks = stats?.total_attacks || 0;
  const attackRate = stats?.attack_rate || (totalFlows > 0 ? (totalAttacks / totalFlows) * 100 : 0);
  const normalRate = totalFlows > 0 ? (normalTraffic / totalFlows) * 100 : 0;

  const severityCounts = stats?.severity_counts || { Critical: 0, High: 0, Medium: 0, Normal: 0 };
  const categoryCounts = stats?.category_counts || { DDoS: 0, DoS: 0, 'Brute Force': 0, 'Port Scan': 0 };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2.5 font-mono">
      {/* 1. Total Flows */}
      <div className="bg-[#1a1a1a] border border-[#2a2a2a] p-3 flex flex-col justify-between">
        <div className="flex items-center justify-between text-[#888888] text-[11px] font-bold tracking-wider">
          <span>[ TOTAL FLOWS ]</span>
          <span className="text-[#888888]">CAP</span>
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-xl sm:text-2xl font-bold text-[#ffffff]">
            {totalFlows.toLocaleString()}
          </span>
        </div>
        <div className="border-t border-[#2a2a2a] pt-1.5 mt-2 text-[10px] text-[#888888]">
          All processed sessions
        </div>
      </div>

      {/* 2. Normal Traffic */}
      <div className="bg-[#1a1a1a] border border-[#2a2a2a] p-3 flex flex-col justify-between">
        <div className="flex items-center justify-between text-[#888888] text-[11px] font-bold tracking-wider">
          <span>[ NORMAL TRAFFIC ]</span>
          <span className="w-1.5 h-1.5 bg-[#00c853]" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-xl sm:text-2xl font-bold text-[#00c853]">
            {normalTraffic.toLocaleString()}
          </span>
          <span className="text-xs text-[#00c853]/80">
            {normalRate.toFixed(1)}%
          </span>
        </div>
        <div className="border-t border-[#2a2a2a] pt-1.5 mt-2 text-[10px] text-[#888888]">
          Benign network flows
        </div>
      </div>

      {/* 3. Total Attacks */}
      <div className="bg-[#1a1a1a] border border-[#2a2a2a] p-3 flex flex-col justify-between">
        <div className="flex items-center justify-between text-[#888888] text-[11px] font-bold tracking-wider">
          <span>[ TOTAL ATTACKS ]</span>
          <span className="w-1.5 h-1.5 bg-red-500 animate-pulse" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-xl sm:text-2xl font-bold text-red-400">
            {totalAttacks.toLocaleString()}
          </span>
          <span className="text-xs text-red-400/80">
            {attackRate.toFixed(1)}%
          </span>
        </div>
        <div className="border-t border-[#2a2a2a] pt-1.5 mt-2 text-[10px] text-red-400/70">
          Anomalous / Exploit
        </div>
      </div>

      {/* 4. Critical (DDoS & DoS) */}
      <div className="bg-[#1a1a1a] border border-[#2a2a2a] border-l-2 border-l-red-500 p-3 flex flex-col justify-between">
        <div className="flex items-center justify-between text-red-400 text-[11px] font-bold tracking-wider">
          <span>[ CRITICAL ]</span>
          <span className="text-[10px] text-red-400">
            DDoS / DoS
          </span>
        </div>
        <div className="mt-2">
          <span className="text-xl sm:text-2xl font-bold text-red-400">
            {(severityCounts.Critical || 0).toLocaleString()}
          </span>
        </div>
        <div className="border-t border-[#2a2a2a] pt-1.5 mt-2 text-[10px] text-[#888888] flex justify-between">
          <span>DDoS: {categoryCounts.DDoS || 0}</span>
          <span>DoS: {categoryCounts.DoS || 0}</span>
        </div>
      </div>

      {/* 5. High (Brute Force) */}
      <div className="bg-[#1a1a1a] border border-[#2a2a2a] border-l-2 border-l-orange-500 p-3 flex flex-col justify-between">
        <div className="flex items-center justify-between text-orange-400 text-[11px] font-bold tracking-wider">
          <span>[ HIGH ]</span>
          <span className="text-[10px] text-orange-400">
            Brute Force
          </span>
        </div>
        <div className="mt-2">
          <span className="text-xl sm:text-2xl font-bold text-orange-400">
            {(severityCounts.High || 0).toLocaleString()}
          </span>
        </div>
        <div className="border-t border-[#2a2a2a] pt-1.5 mt-2 text-[10px] text-[#888888]">
          SSH / FTP / Web Auth
        </div>
      </div>

      {/* 6. Medium (Port Scan) */}
      <div className="bg-[#1a1a1a] border border-[#2a2a2a] border-l-2 border-l-yellow-500 p-3 flex flex-col justify-between">
        <div className="flex items-center justify-between text-yellow-400 text-[11px] font-bold tracking-wider">
          <span>[ MEDIUM ]</span>
          <span className="text-[10px] text-yellow-400">
            Port Scan
          </span>
        </div>
        <div className="mt-2">
          <span className="text-xl sm:text-2xl font-bold text-yellow-400">
            {(severityCounts.Medium || 0).toLocaleString()}
          </span>
        </div>
        <div className="border-t border-[#2a2a2a] pt-1.5 mt-2 text-[10px] text-[#888888]">
          Reconnaissance probes
        </div>
      </div>
    </div>
  );
}
