import React, { useState, useMemo } from 'react';
import { SEVERITY_CONFIG } from '../constants';

export default function FlowTable({ flows, onSelectFlow }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredFlows = useMemo(() => {
    return flows.filter((flow) => {
      if (filterSeverity === 'ATTACKS_ONLY' && !flow.is_attack) return false;
      if (filterSeverity === 'CRITICAL' && flow.severity !== 'Critical') return false;
      if (filterSeverity === 'HIGH' && flow.severity !== 'High') return false;
      if (filterSeverity === 'MEDIUM' && flow.severity !== 'Medium') return false;
      if (filterSeverity === 'NORMAL' && flow.severity !== 'Normal') return false;

      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchIp =
          (flow.src_ip || '').toLowerCase().includes(query) ||
          (flow.dst_ip || '').toLowerCase().includes(query);
        const matchPort =
          String(flow.src_port || '').includes(query) ||
          String(flow.dst_port || '').includes(query);
        const matchLabel = (flow.label || '').toLowerCase().includes(query);
        return matchIp || matchPort || matchLabel;
      }
      return true;
    });
  }, [flows, filterSeverity, searchQuery]);

  const formatDuration = (us) => {
    if (us === undefined || us === null) return '0 µs';
    if (us >= 1000000) {
      return `${(us / 1000000).toFixed(2)}s`;
    }
    return `${Math.round(us).toLocaleString()} µs`;
  };

  return (
    <div className="bg-soc-900 border border-soc-700 rounded-xl overflow-hidden flex flex-col">
      {/* Table Toolbar */}
      <div className="p-4 border-b border-soc-700 flex flex-wrap items-center justify-between gap-4 bg-soc-850/60">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-bold tracking-wide text-white uppercase">Live Flow Stream</h2>
          <span className="text-xs px-2 py-0.5 rounded-full bg-soc-700 text-slate-300 font-mono">
            Showing {filteredFlows.length} of {flows.length} buffered
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Filter tabs */}
          <div className="flex bg-soc-950 p-1 rounded-lg border border-soc-800 text-xs font-medium">
            {[
              { id: 'ALL', label: 'All' },
              { id: 'ATTACKS_ONLY', label: 'Attacks Only' },
              { id: 'CRITICAL', label: 'Critical' },
              { id: 'HIGH', label: 'High' },
              { id: 'MEDIUM', label: 'Medium' },
              { id: 'NORMAL', label: 'Normal' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setFilterSeverity(tab.id)}
                className={`px-2.5 py-1 rounded transition text-xs ${
                  filterSeverity === tab.id
                    ? 'bg-soc-800 text-white font-bold shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Search box */}
          <div className="relative">
            <input
              type="text"
              placeholder="Filter IP / Port / Attack..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-soc-950 border border-soc-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 pl-8 focus:outline-none focus:border-rose-500 font-mono placeholder:text-slate-600 w-56"
            />
            <svg
              width="14"
              height="14"
              className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
          </div>
        </div>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto max-h-[520px]">
        <table className="w-full text-left border-collapse text-xs font-mono">
          <thead>
            <tr className="bg-soc-950/70 border-b border-soc-700 text-slate-400 uppercase text-[11px] tracking-wider sticky top-0 z-20 backdrop-blur">
              <th className="py-2.5 px-4 font-semibold">Flow #</th>
              <th className="py-2.5 px-4 font-semibold">Timestamp</th>
              <th className="py-2.5 px-4 font-semibold">Source</th>
              <th className="py-2.5 px-4 font-semibold">Destination</th>
              <th className="py-2.5 px-4 font-semibold">Proto</th>
              <th className="py-2.5 px-4 font-semibold">Packets</th>
              <th className="py-2.5 px-4 font-semibold">Duration</th>
              <th className="py-2.5 px-4 font-semibold">Classification</th>
              <th className="py-2.5 px-4 font-semibold">Severity</th>
              <th className="py-2.5 px-4 font-semibold">Confidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-soc-800">
            {filteredFlows.length === 0 ? (
              <tr>
                <td colSpan="10" className="py-12 text-center text-slate-500 text-xs">
                  No matching network flows available.
                </td>
              </tr>
            ) : (
              filteredFlows.map((flow) => {
                const cfg = SEVERITY_CONFIG[flow.severity] || SEVERITY_CONFIG.Normal;
                const timeStr = flow.timestamp ? (flow.timestamp.split(' ')[1] || flow.timestamp) : '--:--:--';

                return (
                  <tr
                    key={`flow-${flow.id}-${flow.epoch || flow.timestamp}`}
                    onClick={() => onSelectFlow(flow)}
                    className={`hover:bg-soc-800/80 transition cursor-pointer ${
                      flow.severity === 'Critical' ? 'bg-red-950/20' : ''
                    }`}
                  >
                    <td className="py-2.5 px-4 text-slate-400 font-bold">#{flow.id}</td>
                    <td className="py-2.5 px-4 text-slate-300">{timeStr}</td>
                    <td className="py-2.5 px-4 text-rose-300">
                      {flow.src_ip}:{flow.src_port}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {flow.dst_ip}:{flow.dst_port}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 uppercase">{flow.protocol}</td>
                    <td className="py-2.5 px-4 text-slate-300">{flow.packet_count}</td>
                    <td className="py-2.5 px-4 text-slate-400">
                      {formatDuration(flow.duration_us)}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`font-semibold ${cfg.textClass}`}>{flow.label}</span>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${cfg.bgBadge}`}>
                        {cfg.label}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {flow.confidence !== null && flow.confidence !== undefined ? (
                        `${(flow.confidence * 100).toFixed(1)}%`
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
