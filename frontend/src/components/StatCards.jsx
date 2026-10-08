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
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
      {/* 1. Total Flows */}
      <div className="bg-soc-900 border border-soc-700 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
          <span>TOTAL FLOWS</span>
          <span className="text-slate-500">Captured</span>
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-white">
            {totalFlows.toLocaleString()}
          </span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500 font-mono">
          All processed sessions
        </div>
      </div>

      {/* 2. Normal Traffic */}
      <div className="bg-soc-900 border border-soc-700 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
          <span>NORMAL TRAFFIC</span>
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-emerald-400">
            {normalTraffic.toLocaleString()}
          </span>
          <span className="text-xs font-mono text-emerald-500/80">
            {normalRate.toFixed(1)}%
          </span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500 font-mono">
          Benign network flows
        </div>
      </div>

      {/* 3. Total Attacks */}
      <div className="bg-soc-900 border border-soc-700 rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
          <span>TOTAL ATTACKS</span>
          <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-rose-400">
            {totalAttacks.toLocaleString()}
          </span>
          <span className="text-xs font-mono text-rose-500/80">
            {attackRate.toFixed(1)}%
          </span>
        </div>
        <div className="mt-2 text-[11px] text-rose-400/70 font-mono">
          Anomalous / Exploit traffic
        </div>
      </div>

      {/* 4. Critical (DDoS & DoS) */}
      <div className="bg-gradient-to-br from-red-950/40 to-soc-900 border border-red-600/40 rounded-xl p-4 flex flex-col justify-between shadow-lg shadow-red-950/20">
        <div className="flex items-center justify-between text-red-300 text-xs font-bold tracking-wide">
          <span>CRITICAL</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-mono">
            DDoS / DoS
          </span>
        </div>
        <div className="mt-2">
          <span className="text-2xl font-bold font-mono text-red-400">
            {(severityCounts.Critical || 0).toLocaleString()}
          </span>
        </div>
        <div className="mt-2 text-[11px] text-red-300/70 font-mono flex justify-between">
          <span>DDoS: {categoryCounts.DDoS || 0}</span>
          <span>DoS: {categoryCounts.DoS || 0}</span>
        </div>
      </div>

      {/* 5. High (Brute Force) */}
      <div className="bg-gradient-to-br from-orange-950/40 to-soc-900 border border-orange-600/40 rounded-xl p-4 flex flex-col justify-between shadow-lg shadow-orange-950/20">
        <div className="flex items-center justify-between text-orange-300 text-xs font-bold tracking-wide">
          <span>HIGH</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 font-mono">
            Brute Force
          </span>
        </div>
        <div className="mt-2">
          <span className="text-2xl font-bold font-mono text-orange-400">
            {(severityCounts.High || 0).toLocaleString()}
          </span>
        </div>
        <div className="mt-2 text-[11px] text-orange-300/70 font-mono">
          SSH / FTP / Web credentials
        </div>
      </div>

      {/* 6. Medium (Port Scan) */}
      <div className="bg-gradient-to-br from-yellow-950/40 to-soc-900 border border-yellow-600/40 rounded-xl p-4 flex flex-col justify-between shadow-lg shadow-yellow-950/20">
        <div className="flex items-center justify-between text-yellow-300 text-xs font-bold tracking-wide">
          <span>MEDIUM</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-400 font-mono">
            Port Scan
          </span>
        </div>
        <div className="mt-2">
          <span className="text-2xl font-bold font-mono text-yellow-400">
            {(severityCounts.Medium || 0).toLocaleString()}
          </span>
        </div>
        <div className="mt-2 text-[11px] text-yellow-300/70 font-mono">
          Reconnaissance probes
        </div>
      </div>
    </div>
  );
}
